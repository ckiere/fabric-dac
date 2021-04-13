package msp

import (
	"encoding/json"
	"github.com/dbogatov/dac-lib/dac"
)

type DacConfig struct {
	Hbytes      []byte   `json:"h"`
	YsBytes1    [][]byte `json:"ys1"`
	YsBytes2    [][]byte `json:"ys2"`
	RootPkBytes []byte   `json:"rootpk"`
}

func (c *DacConfig) H() (interface{}, error) {
	return dac.PointFromBytes(c.Hbytes)
}

func (c *DacConfig) Ys() ([][]interface{}, error) {
	var err error
	Ys := make([][]interface{}, 2)
	Ys[0] = make([]interface{}, len(c.YsBytes2))
	for index, yBytes := range c.YsBytes2 {
		Ys[0][index], err = dac.PointFromBytes(yBytes)
		if err != nil {
			return nil, err
		}
	}
	Ys[1] = make([]interface{}, len(c.YsBytes1))
	for index, yBytes := range c.YsBytes1 {
		Ys[1][index], err = dac.PointFromBytes(yBytes)
		if err != nil {
			return nil, err
		}
	}
	return Ys, nil
}

func (c *DacConfig) RootPk() (interface{}, error) {
	return dac.PointFromBytes(c.RootPkBytes)
}

func CreateDacConfigFromBytes(configBytes []byte) (*DacConfig, error) {
	dacConfig := DacConfig{}

	err := json.Unmarshal(configBytes, &dacConfig)
	if err != nil {
		return nil, err
	}

	return &dacConfig, nil
}
