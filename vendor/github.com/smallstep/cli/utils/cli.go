package utils

import (
	"github.com/smallstep/cli/errs"
	"github.com/urfave/cli"
)

// DefaultRSASize sets the default key size for RSA to 2048 bits.
const DefaultRSASize = 2048

// DefaultECCurve sets the default curve for EC to P-256.
const DefaultECCurve = "P-256"

// GetKeyDetailsFromCLI gets the key pair algorithm, curve, and size inputs
// from the CLI context.
func GetKeyDetailsFromCLI(ctx *cli.Context, insecure bool, ktyKey, curveKey, sizeKey string) (string, string, int, error) {
	var (
		crv  = ctx.String("curve")
		size = ctx.Int("size")
		kty  = ctx.String("kty")
	)

	if ctx.IsSet(ktyKey) {
		switch kty {
		case "RSA":
			if !ctx.IsSet(sizeKey) {
				size = DefaultRSASize
			}
			if ctx.IsSet(curveKey) {
				return kty, crv, size, errs.IncompatibleFlagValue(ctx, curveKey, ktyKey, kty)
			}
			if size < 2048 && !insecure {
				return kty, crv, size, errs.MinSizeInsecureFlag(ctx, sizeKey, "2048")
			}
			if size <= 0 {
				return kty, crv, size, errs.MinSizeFlag(ctx, sizeKey, "0")
			}
		case "EC":
			if ctx.IsSet("size") {
				return kty, crv, size, errs.IncompatibleFlagValue(ctx, sizeKey, ktyKey, kty)
			}
			if !ctx.IsSet("curve") {
				crv = DefaultECCurve
			}
			switch crv {
			case "P-256", "P-384", "P-521": //ok
			default:
				return kty, crv, size, errs.IncompatibleFlagValueWithFlagValue(ctx, ktyKey, kty,
					curveKey, crv, "P-256, P-384, P-521")
			}
		case "OKP":
			if ctx.IsSet("size") {
				return kty, crv, size, errs.IncompatibleFlagValue(ctx, sizeKey, ktyKey, kty)
			}
			switch crv {
			case "Ed25519": //ok
			case "": // ok: OKP defaults to Ed25519
				crv = "Ed25519"
			default:
				return kty, crv, size, errs.IncompatibleFlagValueWithFlagValue(ctx, ktyKey, kty,
					curveKey, crv, "Ed25519")
			}
		default:
			return kty, crv, size, errs.InvalidFlagValue(ctx, ktyKey, kty, "RSA, EC, OKP")
		}
	} else {
		if ctx.IsSet(curveKey) {
			return kty, crv, size, errs.RequiredWithFlag(ctx, curveKey, ktyKey)
		}
		if ctx.IsSet("size") {
			return kty, crv, size, errs.RequiredWithFlag(ctx, sizeKey, ktyKey)
		}
		// Set default key type | curve | size.
		kty = "EC"
		crv = "P-256"
		size = 0
	}
	return kty, crv, size, nil
}
