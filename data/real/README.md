# Real public sample: loghub OpenSSH_2k

`OpenSSH_2k.log` is an unmodified 2,000-line excerpt of a real SSH server log
(host `LabSZ`, December 2015) from **loghub**, a public collection of system logs
for research.

- Source: https://github.com/logpai/loghub/blob/374038faa4ca122dd7ca0730372c0b78f76f8597/OpenSSH/OpenSSH_2k.log
- It is used here only for a non-commercial portfolio demonstration of log analysis.
- The IP addresses in it are those of the internet hosts that attacked the lab
  server in 2015, as already published in the dataset. No labels exist for this
  file, so it is used to show the parser and rules working on real traffic, not
  to measure accuracy.

Try it:

```bash
logsentinel ingest data/real/OpenSSH_2k.log --year 2015
logsentinel alerts
```

## Licence notice (required by loghub)

> LICENSE OF LOGHUB
>
> The datasets are freely available for research or academic work, subject to
> the following condition: For any usage or distribution of the loghub datasets,
> please refer to the loghub repository URL (https://github.com/logpai/loghub)
> and cite the following loghub paper where applicable.
>
> Jieming Zhu, Shilin He, Pinjia He, Jinyang Liu, Michael R. Lyu. Loghub: A Large
> Collection of System Log Datasets for AI-driven Log Analytics. In ISSRE, 2023.
>
> The above license notice shall be included in all copies of the datasets.

Note: this licence is separate from the MIT licence of LogSentinel's code and
applies only to `OpenSSH_2k.log`.
