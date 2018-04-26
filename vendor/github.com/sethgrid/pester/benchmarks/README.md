# Timing Tests

It was noted in [issue #2](github.com/sethgrid/pester/issue/2) that Pester may be slower than the standard library (along with bug that was fixed).

I put together a quick test to see how Pester fairs against the stand library. Here are the results:

```
$ go test
  Standard Library Get           675178 ns Avg.
  Pester, Default                690157 ns Avg.
  Pester, Retries 1, Conc 1      671322 ns Avg.
  Pester, Retries 2, Conc 2      764386 ns Avg.
  Pester, Retries 3, Conc 3      893899 ns Avg.
  Pester, Retries 0, Conc 1      730407 ns Avg.
  Pester, Retries 0, Conc 2     1077721 ns Avg.
  Pester, Retries 0, Conc 3     1889403 ns Avg.
  Pester, Retries 0, Conc 1     1758464 ns Avg.
  Pester, Retries 2, Conc 1     1249081 ns Avg.
  Pester, Retries 3, Conc 1     1824322 ns Avg.
PASS
```

Running the test locally multiple times shows some variance, but this is a typical result. In raw time, these average times are not far off from each other (about 1ms from the best to worst case). In comparisons between percents, we see a drift of up to 3x.

The up to 3x drift between the near identical default Pester implementation and the Standard Library http.Get call compared to the last test case of 'Retries 3, Conc 1' makes little sense in that the default Pester uses 'Retries 3, Conc 1' as its settings.

I think that it is safe to say that there is no material difference in speed between the Standard Library and Pester. 
