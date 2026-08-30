# 模型能力统计评测：v2-p1-release-ubuntu-24.04-arm64-2026-08-30

- 结果：**PASS**
- 时间：2026-08-30T04:00:44.089Z
- 模型：siliconflow/deepseek-ai/DeepSeek-V4-Flash

| 指标 | 数值 | 分子/分母 | 门槛 | 结果 |
| --- | ---: | ---: | ---: | --- |
| factReachability | 100.00% | 2/2 | >= 90.00% | PASS |
| truncationLoss | 0.00% | 0/11 | <= 5.00% | PASS |
| modelNotConcluded | 0.00% | 0/2 | <= 10.00% | PASS |
| presetPartial | 0.00% | 0/2 | <= 10.00% | PASS |
| novelRecall | 100.00% | 1/1 | >= 80.00% | PASS |
| invalidToolCalls | 0.00% | 0/11 | <= 5.00% | PASS |
| benignFalsePositive | 0.00% | 0/1 | <= 5.00% | PASS |

## 成本与裁定

- Token：input=23499，output=5115，cacheRead=34816，cacheWrite=0，total=63430
- 延迟：epochWall=225934ms，modelToolWall=22ms
- 远程成本：calls=0，nodes=0，bytes=0，wall=0ms，probe=0
- 规则裁定：risky=1，humanAdjudicated=0，humanOverturned=0
