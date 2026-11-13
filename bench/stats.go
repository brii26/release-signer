package main

import (
	"errors"
	"math"
	"sort"
)

type statistics struct {
	Samples  int     `json:"samples"`
	MedianNS float64 `json:"median_ns"`
	P95NS    int64   `json:"p95_ns"`
}

// summarize copies the samples: raw CSVs retain their measurement order.
func summarize(samples []int64) (statistics, error) {
	if len(samples) == 0 {
		return statistics{}, errors.New("cannot summarize empty samples")
	}
	sorted := append([]int64(nil), samples...)
	for _, n := range sorted {
		if n < 0 {
			return statistics{}, errors.New("negative duration")
		}
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	middle := len(sorted) / 2
	median := float64(sorted[middle])
	if len(sorted)%2 == 0 {
		median = float64(sorted[middle-1])/2 + float64(sorted[middle])/2
	}
	return statistics{len(sorted), median, sorted[int(math.Ceil(.95*float64(len(sorted))))-1]}, nil
}
