package cmp

import (
	"context"
	"fmt"
)

func (a *Cmp) Setup(ctx context.Context) error {
	fmt.Println("## CMP Setup called")
	return nil
}
