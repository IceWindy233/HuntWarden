# 模型能力统计评测：v2-release-ubuntu-24.04-arm64-2026-08-26

- 结果：**PASS**
- 时间：2026-08-26T13:29:33.173Z
- 模型：siliconflow/deepseek-ai/DeepSeek-V4-Flash

| 指标 | 数值 | 分子/分母 | 门槛 | 结果 |
| --- | ---: | ---: | ---: | --- |
| factReachability | 100.00% | 2/2 | >= 90.00% | PASS |
| truncationLoss | 0.00% | 0/22 | <= 5.00% | PASS |
| modelNotConcluded | 0.00% | 0/2 | <= 10.00% | PASS |
| presetPartial | 0.00% | 0/2 | <= 10.00% | PASS |
| novelRecall | 100.00% | 1/1 | >= 80.00% | PASS |
| invalidToolCalls | 0.00% | 0/22 | <= 5.00% | PASS |
| benignFalsePositive | 0.00% | 0/1 | <= 5.00% | PASS |

## 成本与裁定

- Token：input=44886，output=12335，cacheRead=110336，cacheWrite=0，total=167557
- 延迟：epochWall=496894ms，modelToolWall=782ms
- 远程成本：calls=3，nodes=2，bytes=1425，wall=2ms，probe=0
- 规则裁定：risky=3，humanAdjudicated=0，humanOverturned=0
