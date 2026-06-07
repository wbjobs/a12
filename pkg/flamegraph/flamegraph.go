package flamegraph

import (
	"fmt"
	"hash/fnv"
	"html"
	"sort"
	"strings"
	"time"

	"github.com/ebpf-tracing/ebpf-apm/pkg/model"
)

type FlameFrame struct {
	Name      string
	Service   string
	Value     int64
	Children  []*FlameFrame
	StartTime time.Time
	EndTime   time.Time
	Duration  float64
	SpanID    string
}

type FlameGraph struct {
	Root  *FlameFrame
	Title string
	Width int
}

type FrameStats struct {
	TotalTime   float64
	SelfTime    float64
	CallCount   int
	Percentage  float64
}

type SVGConfig struct {
	Width         int
	HeightPerFrame int
	FontSize      int
	Title         string
	Colors        ColorPalette
}

type ColorPalette struct {
	BaseHue        int
	HueRange       int
	MinSaturation  int
	MaxSaturation  int
	MinLightness   int
	MaxLightness   int
}

var DefaultColorPalette = ColorPalette{
	BaseHue:       200,
	HueRange:      60,
	MinSaturation: 70,
	MaxSaturation: 90,
	MinLightness:  40,
	MaxLightness:  70,
}

var DefaultSVGConfig = SVGConfig{
	Width:          1200,
	HeightPerFrame: 18,
	FontSize:       12,
	Title:          "Trace Flame Graph",
	Colors:         DefaultColorPalette,
}

func NewFlameGraph(root *model.Span, title string) *FlameGraph {
	if root == nil {
		return nil
	}

	flameRoot := convertSpanToFlameFrame(root, nil)

	return &FlameGraph{
		Root:  flameRoot,
		Title: title,
		Width: 1200,
	}
}

func convertSpanToFlameFrame(span *model.Span, _ *FlameFrame) *FlameFrame {
	name := fmt.Sprintf("%s:%s", span.ServiceName, span.Operation)
	if span.Protocol != "" {
		name = fmt.Sprintf("%s [%s]", name, span.Protocol)
	}

	frame := &FlameFrame{
		Name:      name,
		Service:   span.ServiceName,
		Value:     int64(span.DurationMs * 1000),
		StartTime: span.StartTime,
		EndTime:   span.EndTime,
		Duration:  span.DurationMs,
		SpanID:    span.SpanID,
	}

	if len(span.Children) > 0 {
		sort.Slice(span.Children, func(i, j int) bool {
			return span.Children[i].StartTime.Before(span.Children[j].StartTime)
		})

		frame.Children = make([]*FlameFrame, 0, len(span.Children))
		for _, child := range span.Children {
			childFrame := convertSpanToFlameFrame(child, frame)
			frame.Children = append(frame.Children, childFrame)
		}
	}

	return frame
}

func (fg *FlameGraph) ToFolded() string {
	var lines []string
	var stack []string
	fg.collectFolded(fg.Root, stack, &lines)
	return strings.Join(lines, "\n")
}

func (fg *FlameGraph) collectFolded(frame *FlameFrame, stack []string, lines *[]string) {
	currentStack := append(stack, frame.Name)
	stackStr := strings.Join(currentStack, ";")

	line := fmt.Sprintf("%s %d", stackStr, frame.Value)
	*lines = append(*lines, line)

	for _, child := range frame.Children {
		fg.collectFolded(child, currentStack, lines)
	}
}

func (fg *FlameGraph) ToSVG(config *SVGConfig) (string, error) {
	if config == nil {
		config = &DefaultSVGConfig
	}

	if config.Colors.BaseHue == 0 {
		config.Colors = DefaultColorPalette
	}

	maxDepth := fg.calculateMaxDepth(fg.Root, 1)
	height := 20 + maxDepth*config.HeightPerFrame + 40

	var sb strings.Builder

	sb.WriteString(fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" font-family="Verdana, sans-serif" font-size="%d">`,
		config.Width, height, config.FontSize))

	sb.WriteString(fmt.Sprintf(`<title>%s</title>`, html.EscapeString(config.Title)))

	sb.WriteString(`<defs>
    <linearGradient id="titleGradient" x1="0%" y1="0%" x2="0%" y2="100%">
      <stop offset="0%" style="stop-color:#f5f5f5;stop-opacity:1" />
      <stop offset="100%" style="stop-color:#e0e0e0;stop-opacity:1" />
    </linearGradient>
  </defs>`)

	sb.WriteString(fmt.Sprintf(`<rect width="%d" height="25" fill="url(#titleGradient)"/>`, config.Width))
	sb.WriteString(fmt.Sprintf(`<text x="%d" y="17" text-anchor="middle" font-weight="bold" fill="#333">%s</text>`,
		config.Width/2, html.EscapeString(config.Title)))

	totalValue := float64(fg.Root.Value)
	if totalValue == 0 {
		totalValue = 1
	}

	svgWidth := float64(config.Width)
	frameHeight := float64(config.HeightPerFrame)

	fg.drawFrame(&sb, fg.Root, 0, 25, svgWidth, frameHeight, totalValue, config, 0)

	sb.WriteString(fmt.Sprintf(`<text x="5" y="%d" font-size="%d" fill="#666">Total: %.2fms</text>`,
		height-10, config.FontSize-1, fg.Root.Duration))
	sb.WriteString(fmt.Sprintf(`<text x="%d" y="%d" text-anchor="end" font-size="%d" fill="#666">Depth: %d</text>`,
		config.Width-5, height-10, config.FontSize-1, maxDepth))

	sb.WriteString(`</svg>`)

	return sb.String(), nil
}

func (fg *FlameGraph) drawFrame(sb *strings.Builder, frame *FlameFrame, x, y, width, height, totalValue float64, config *SVGConfig, depth int) {
	if width < 0.5 {
		return
	}

	color := fg.getColor(frame, depth, config)

	tooltip := fmt.Sprintf("%s\nDuration: %.2fms\nService: %s\nSpanID: %s",
		frame.Name, frame.Duration, frame.Service, frame.SpanID)

	sb.WriteString(fmt.Sprintf(`<g class="frame">`))

	sb.WriteString(fmt.Sprintf(`<title>%s</title>`, html.EscapeString(tooltip)))

	sb.WriteString(fmt.Sprintf(`<rect x="%.2f" y="%.2f" width="%.2f" height="%.2f" fill="%s" stroke="#fff" stroke-width="1" rx="2" ry="2"/>`,
		x, y, width, height-1, color))

	text := frame.Name
	if width > 80 {
		maxChars := int(width / float64(config.FontSize) * 1.8)
		if len(text) > maxChars {
			text = text[:maxChars-3] + "..."
		}

		sb.WriteString(fmt.Sprintf(`<text x="%.2f" y="%.2f" font-size="%d" fill="#fff" pointer-events="none">%s</text>`,
			x+5, y+height-5, config.FontSize-2, html.EscapeString(text)))
	}

	sb.WriteString(`</g>`)

	childY := y + height
	childX := x

	for _, child := range frame.Children {
		childWidth := float64(child.Value) / totalValue * float64(config.Width)
		fg.drawFrame(sb, child, childX, childY, childWidth, height, totalValue, config, depth+1)
		childX += childWidth
	}
}

func (fg *FlameGraph) getColor(frame *FlameFrame, depth int, config *SVGConfig) string {
	h := fnv.New32a()
	h.Write([]byte(frame.Name))
	hash := h.Sum32()

	hue := config.Colors.BaseHue + int(hash)%config.Colors.HueRange
	saturation := config.Colors.MinSaturation + int(hash>>8)%(config.Colors.MaxSaturation-config.Colors.MinSaturation)
	lightness := config.Colors.MaxLightness - depth*3
	if lightness < config.Colors.MinLightness {
		lightness = config.Colors.MinLightness
	}

	if frame.Duration > 500 {
		saturation = 90
		hue = 0
	} else if frame.Duration > 200 {
		hue = 30
		saturation = 80
	}

	return fmt.Sprintf("hsl(%d, %d%%, %d%%)", hue, saturation, lightness)
}

func (fg *FlameGraph) calculateMaxDepth(frame *FlameFrame, currentDepth int) int {
	if len(frame.Children) == 0 {
		return currentDepth
	}

	maxDepth := currentDepth
	for _, child := range frame.Children {
		d := fg.calculateMaxDepth(child, currentDepth+1)
		if d > maxDepth {
			maxDepth = d
		}
	}
	return maxDepth
}

func (fg *FlameGraph) GetFrameStats() map[string]*FrameStats {
	stats := make(map[string]*FrameStats)
	total := float64(fg.Root.Value)
	fg.collectFrameStats(fg.Root, stats, total)
	return stats
}

func (fg *FlameGraph) collectFrameStats(frame *FlameFrame, stats map[string]*FrameStats, total float64) {
	if s, ok := stats[frame.Name]; ok {
		s.TotalTime += frame.Duration
		s.CallCount++
	} else {
		stats[frame.Name] = &FrameStats{
			TotalTime:  frame.Duration,
			SelfTime:   0,
			CallCount:  1,
			Percentage: frame.Duration / fg.Root.Duration * 100,
		}
	}

	childTime := 0.0
	for _, child := range frame.Children {
		childTime += child.Duration
		fg.collectFrameStats(child, stats, total)
	}
	stats[frame.Name].SelfTime = frame.Duration - childTime
	stats[frame.Name].Percentage = stats[frame.Name].TotalTime / fg.Root.Duration * 100
}

func (fg *FlameGraph) GetHotSpots(count int) []*FlameFrame {
	var allFrames []*FlameFrame
	fg.collectAllFrames(fg.Root, &allFrames)

	sort.Slice(allFrames, func(i, j int) bool {
		selfTimeI := allFrames[i].Duration
		for _, c := range allFrames[i].Children {
			selfTimeI -= c.Duration
		}
		selfTimeJ := allFrames[j].Duration
		for _, c := range allFrames[j].Children {
			selfTimeJ -= c.Duration
		}
		return selfTimeI > selfTimeJ
	})

	if count > 0 && count < len(allFrames) {
		return allFrames[:count]
	}
	return allFrames
}

func (fg *FlameGraph) collectAllFrames(frame *FlameFrame, frames *[]*FlameFrame) {
	*frames = append(*frames, frame)
	for _, child := range frame.Children {
		fg.collectAllFrames(child, frames)
	}
}
