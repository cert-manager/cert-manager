# README

cert-manager follows the [Kubernetes conventions for third_party code]:

- forked third party Go code goes in `third_party/forked`.
- forked _golang stdlib_ code goes in `third_party/forked/golang`.

Third-party code must include licenses. This includes modified third-party code and excerpts, as well.

[Kubernetes conventions for third_party code]: https://github.com/kubernetes/community/blob/master/contributors/guide/coding-conventions.md#directory-and-file-conventions

To update the `third_party/` code:

```bash
make update-third-party
```

To add a new `third_party/` sub-folder:
- Add the new folder and the source repo to `klone.yaml`
- Update `make/third_party.mk` to perform an additional post-processing of the cloned files.
- Update the import statements in any cert-manager Go packages to import the package from the third_party folder instead of the upstream Go module.
