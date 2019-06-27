package internal

// CustomMetric is a custom metric.
type CustomMetric struct {
	RawInputName string
	Value        float64
}

// MergeIntoHarvest implements Harvestable.
func (m CustomMetric) MergeIntoHarvest(h *Harvest) {
	h.Metrics.addValue(customMetric(m.RawInputName), "", m.Value, unforced)
}
