# Logic for deprecating securityContext.enabled

The idea is to be able to define a `securityContext` from an arbitrary yaml block without being restricted to just the attributes currently supported.

For example, by supporting a block like the following in the `values.yaml` file:

```yaml
securityContext:
  fsGroup: 1111
  runAsUser: 2222
  runAsNonRoot: true
```

The logic for supporting the new `securityContext` in the `values.yaml` file should be backwards compatible with the `securityContext.enabled` parameter.

## Pseudo-code logic

No security context block should be defined if:

```
securityContext is empty
or securityContext.enabled is defined and securityContext.enabled is false
```

Otherwise a securityContext block should be defined

When a securityContext block has to be generated, we should fall back and support the deprecated structure if:

```
securityContext.enabled is true
```

Otherwise, we copy the `securityContext` block as it is to support the new format.

## Test cases

### Test case 1

Defaults

Input:

No security context specified

Output:

Nothing generated

### Test case 2

Legacy parameters with `enabled` only and no additional parameters

Input:

```yaml
securityContext:
  enabled: true
```

Output:

```yaml
securityContext:
  fsGroup: 1001
  runAsUser: 1001
```

### Test case 3

Legacy parameters with `enabled`, group and user

Input:

```yaml
securityContext:
  enabled: true
  fsGroup: 1111
  runAsUser: 2222
```

Output:

```yaml
securityContext:
  fsGroup: 1111
  runAsUser: 2222
```

### Test case 4:

New default format

Input:

```yaml
securityContext: {}
```

Output:

```yaml
```

### Test case 5:

New format with arbitrary block

Input:

```yaml
securityContext:
  fsGroup: 1111
  runAsUser: 2222
  runAsNonRoot: true
```

Output:

```yaml
securityContext:
  fsGroup: 1111
  runAsNonRoot: true
  runAsUser: 2222
```

### Test case 6:

Legacy parameters with `enabled` set to false and extra parameters that should be ignored

Input:

```yaml
securityContext:
  enabled: false
  fsGroup: 1111
  runAsUser: 2222
```

Output:

```yaml
```

### Test case 7:

Legacy parameters with `enabled` set to false

Input:

```yaml
securityContext:
  enabled: false
```

Output:

```yaml
```

### Test case 8:

Block with only fsGroup and runAsUser

Input:

```yaml
securityContext:
  fsGroup: 1111
  runAsUser: 2222
```

Output:

```yaml
securityContext:
  fsGroup: 1111
  runAsUser: 2222
```
