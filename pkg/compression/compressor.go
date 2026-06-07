package compression

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"sort"
	"strings"
	"sync"

	"github.com/ebpf-tracing/ebpf-apm/pkg/model"
	"github.com/klauspost/compress/zstd"
)

type SubtreeSignature struct {
	Hash       string
	Structure  string
	Operations []string
	Depth      int
	Count      int64
}

type CompressedSpan struct {
	*model.Span
	Children         []*CompressedSpan `json:"children,omitempty"`
	CompressedData   []byte            `json:"compressed_data,omitempty"`
	CompressionRatio float64           `json:"compression_ratio,omitempty"`
	IsCompressed     bool              `json:"is_compressed,omitempty"`
	SignatureHash    string            `json:"signature_hash,omitempty"`
	OriginalSize     int               `json:"original_size,omitempty"`
	CompressedSize   int               `json:"compressed_size,omitempty"`
}

type CompressionStats struct {
	TotalSpans       int64
	CompressedSpans  int64
	TotalOriginal    int64
	TotalCompressed  int64
	CompressionRatio float64
	CacheHits        int64
	CacheMisses      int64
}

type Compressor struct {
	encoder            *zstd.Encoder
	decoder            *zstd.Decoder
	signatureCache     map[string]*SubtreeSignature
	signatureCacheMu   sync.RWMutex
	stats              CompressionStats
	statsMu            sync.RWMutex
	maxCacheSize       int
	compressionLevel   zstd.EncoderLevel
	similarityThreshold float64
}

type CompressorConfig struct {
	CompressionLevel    int     `mapstructure:"compression_level"`
	MaxCacheSize        int     `mapstructure:"max_cache_size"`
	SimilarityThreshold float64 `mapstructure:"similarity_threshold"`
}

func NewCompressor(config *CompressorConfig) (*Compressor, error) {
	if config == nil {
		config = &CompressorConfig{
			CompressionLevel:    3,
			MaxCacheSize:        10000,
			SimilarityThreshold: 0.9,
		}
	}

	level := zstd.EncoderLevelFromZstd(config.CompressionLevel)
	encoder, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(level))
	if err != nil {
		return nil, fmt.Errorf("failed to create zstd encoder: %w", err)
	}

	decoder, err := zstd.NewReader(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create zstd decoder: %w", err)
	}

	return &Compressor{
		encoder:             encoder,
		decoder:             decoder,
		signatureCache:      make(map[string]*SubtreeSignature),
		maxCacheSize:        config.MaxCacheSize,
		compressionLevel:    level,
		similarityThreshold: config.SimilarityThreshold,
	}, nil
}

func (c *Compressor) CompressSpan(span *model.Span) (*CompressedSpan, error) {
	if span == nil {
		return nil, nil
	}

	c.statsMu.Lock()
	c.stats.TotalSpans++
	c.statsMu.Unlock()

	compressed := &CompressedSpan{
		Span: span,
	}

	data, err := json.Marshal(span)
	if err != nil {
		return compressed, nil
	}

	originalSize := len(data)
	if originalSize < 256 {
		return compressed, nil
	}

	compressedData := c.encoder.EncodeAll(data, nil)
	compressedSize := len(compressedData)

	ratio := float64(originalSize) / float64(compressedSize)
	if ratio < 1.2 {
		return compressed, nil
	}

	compressed.CompressedData = compressedData
	compressed.IsCompressed = true
	compressed.CompressionRatio = ratio
	compressed.OriginalSize = originalSize
	compressed.CompressedSize = compressedSize

	span.Tags["compressed"] = true
	span.Tags["compression_ratio"] = fmt.Sprintf("%.2f", ratio)
	span.Tags["original_size"] = originalSize
	span.Tags["compressed_size"] = compressedSize

	c.statsMu.Lock()
	c.stats.CompressedSpans++
	c.stats.TotalOriginal += int64(originalSize)
	c.stats.TotalCompressed += int64(compressedSize)
	c.stats.CompressionRatio = float64(c.stats.TotalOriginal) / float64(c.stats.TotalCompressed)
	c.statsMu.Unlock()

	return compressed, nil
}

func (c *Compressor) DecompressSpan(compressed *CompressedSpan) (*model.Span, error) {
	if compressed == nil {
		return nil, nil
	}

	if !compressed.IsCompressed || len(compressed.CompressedData) == 0 {
		return compressed.Span, nil
	}

	data, err := c.decoder.DecodeAll(compressed.CompressedData, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress span: %w", err)
	}

	var span model.Span
	if err := json.Unmarshal(data, &span); err != nil {
		return nil, fmt.Errorf("failed to unmarshal decompressed span: %w", err)
	}

	return &span, nil
}

func (c *Compressor) ComputeSubtreeSignature(root *model.Span) *SubtreeSignature {
	if root == nil {
		return nil
	}

	var operations []string
	structure := c.buildSubtreeStructure(root, "", &operations)

	hash := fnv.New64a()
	hash.Write([]byte(structure))
	hashStr := hex.EncodeToString(hash.Sum(nil))

	sig := &SubtreeSignature{
		Hash:       hashStr,
		Structure:  structure,
		Operations: operations,
		Depth:      countDepth(root),
		Count:      1,
	}

	var isDuplicate bool
	c.signatureCacheMu.Lock()
	if existing, ok := c.signatureCache[hashStr]; ok {
		existing.Count++
		isDuplicate = existing.Count > 1
	} else {
		if len(c.signatureCache) >= c.maxCacheSize {
			c.evictOldCache()
		}
		c.signatureCache[hashStr] = sig
		isDuplicate = false
	}
	c.signatureCacheMu.Unlock()

	c.statsMu.Lock()
	if isDuplicate {
		c.stats.CacheHits++
	} else {
		c.stats.CacheMisses++
	}
	c.statsMu.Unlock()

	return sig
}

func (c *Compressor) buildSubtreeStructure(span *model.Span, indent string, operations *[]string) string {
	var sb strings.Builder
	sb.WriteString(indent)
	sb.WriteString(fmt.Sprintf("%s:%s", span.ServiceName, span.Operation))
	*operations = append(*operations, span.Operation)

	if len(span.Children) > 0 {
		sort.Slice(span.Children, func(i, j int) bool {
			return span.Children[i].StartTime.Before(span.Children[j].StartTime)
		})

		sb.WriteString("[\n")
		for _, child := range span.Children {
			sb.WriteString(c.buildSubtreeStructure(child, indent+"  ", operations))
		}
		sb.WriteString(indent)
		sb.WriteString("]")
	}
	sb.WriteString("\n")

	return sb.String()
}

func countDepth(span *model.Span) int {
	if len(span.Children) == 0 {
		return 1
	}
	maxChild := 0
	for _, child := range span.Children {
		d := countDepth(child)
		if d > maxChild {
			maxChild = d
		}
	}
	return maxChild + 1
}

func (c *Compressor) CompressTrace(root *model.Span) (*CompressedSpan, error) {
	if root == nil {
		return nil, nil
	}

	compressedRoot, err := c.CompressSpan(root)
	if err != nil {
		return nil, err
	}

	sig := c.ComputeSubtreeSignature(root)
	if sig != nil {
		compressedRoot.SignatureHash = sig.Hash
		root.SetTag("subtree_hash", sig.Hash)
		root.SetTag("subtree_depth", sig.Depth)
		root.SetTag("subtree_operations", len(sig.Operations))
		if sig.Count > 1 {
			root.SetTag("subtree_duplicate_count", sig.Count)
		}
	}

	if len(root.Children) > 0 {
		compressedRoot.Children = make([]*CompressedSpan, 0, len(root.Children))
		for _, child := range root.Children {
			compressedChild, err := c.CompressTrace(child)
			if err != nil {
				return nil, err
			}
			if compressedChild != nil {
				compressedRoot.Children = append(compressedRoot.Children, compressedChild)
			}
		}
	}

	return compressedRoot, nil
}

func (c *Compressor) DecompressTrace(compressedRoot *CompressedSpan) (*model.Span, error) {
	if compressedRoot == nil {
		return nil, nil
	}

	rootSpan, err := c.DecompressSpan(compressedRoot)
	if err != nil {
		return nil, err
	}

	if len(compressedRoot.Children) > 0 {
		rootSpan.Children = make([]*model.Span, 0, len(compressedRoot.Children))
		for _, compressedChild := range compressedRoot.Children {
			childSpan, err := c.DecompressTrace(compressedChild)
			if err != nil {
				return nil, err
			}
			if childSpan != nil {
				rootSpan.Children = append(rootSpan.Children, childSpan)
			}
		}
	}

	return rootSpan, nil
}

func (c *Compressor) FindSimilarTraces(sig *SubtreeSignature, threshold float64) []*SubtreeSignature {
	if sig == nil {
		return nil
	}

	c.signatureCacheMu.RLock()
	defer c.signatureCacheMu.RUnlock()

	var similar []*SubtreeSignature
	for _, existing := range c.signatureCache {
		if existing.Hash == sig.Hash {
			continue
		}

		similarity := c.computeSimilarity(sig, existing)
		if similarity >= threshold {
			similar = append(similar, existing)
		}
	}

	return similar
}

func (c *Compressor) computeSimilarity(a, b *SubtreeSignature) float64 {
	if len(a.Operations) == 0 || len(b.Operations) == 0 {
		return 0
	}

	setA := make(map[string]bool)
	for _, op := range a.Operations {
		setA[op] = true
	}

	intersection := 0
	for _, op := range b.Operations {
		if setA[op] {
			intersection++
		}
	}

	union := len(setA) + len(b.Operations) - intersection
	if union == 0 {
		return 0
	}

	return float64(intersection) / float64(union)
}

func (c *Compressor) GetStats() CompressionStats {
	c.statsMu.RLock()
	defer c.statsMu.RUnlock()
	return c.stats
}

func (c *Compressor) GetSignatureCache() map[string]*SubtreeSignature {
	c.signatureCacheMu.RLock()
	defer c.signatureCacheMu.RUnlock()

	result := make(map[string]*SubtreeSignature, len(c.signatureCache))
	for k, v := range c.signatureCache {
		sigCopy := *v
		result[k] = &sigCopy
	}
	return result
}

func (c *Compressor) evictOldCache() {
	oldestKey := ""

	for k, v := range c.signatureCache {
		if v.Count == 1 && oldestKey == "" {
			oldestKey = k
		}
	}

	if oldestKey != "" {
		delete(c.signatureCache, oldestKey)
	} else {
		for k := range c.signatureCache {
			delete(c.signatureCache, k)
			break
		}
	}
}

func (c *Compressor) Close() error {
	c.encoder.Close()
	c.decoder.Close()
	return nil
}
