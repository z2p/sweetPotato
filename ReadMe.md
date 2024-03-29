<a name="wcd7N"></a>
# 免责声明
该工具仅用于安全自查检测<br />由于传播、利用此工具所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。<br />本人拥有对此工具的修改和解释权。未经网络安全部门及相关部门允许，不得善自使用本工具进行任何攻击活动，不得以任何方式将其用于商业目的。
<a name="TEPlj"></a>
# 简介
平时积累的一些攻防经验想做成自动化去提升在公司项目以及外部SRC效果，故闲暇时间开发了这款基于burpsuite的工具。<br />过去在内部使用效果也还可以，现在工作原因不再参与红队类的业务了，将其开源供大家学习分享，过程中大家有发现任何问题和需求，欢迎提交，我会在空余时间进行优化。<br />主要集合了以下几个类别的功能：

1. 资产收集管理的概念，用户可设置域名，插件会随着被动流量进行分析，提取属于目标的域名资产，并会对资产递归访问，快速发现更多业务
2. 被动检测能力：基于代理过去的流量进行分析，尝试提取可疑脆弱点（插件不会发包）
3. 主动检测能力：基于代理过去的流量，然后进行二次加工（插件会额外发包）
4. 提供全局配置管理的界面，可选择对流量以及上述（2）（3）的功能进行配置
5. 当然还提供一些蛮多细小功能，就供大家琢磨了
<a name="bmZSr"></a>
   
# 说明
最近开通了个人blog，针对这个工具的实现和内容细节，我都放在blog上，未来这里只会记录更新日志，[具体blog链接在此 🔗](https://z2p.github.io/posts/%E8%87%AA%E7%A0%94%E4%BF%A1%E6%81%AF%E6%94%B6%E9%9B%86%E5%B7%A5%E5%85%B7%E5%88%86%E4%BA%AB/)

# 功能演示
核心只演示资产收集管理的功能，其他功能大家可以慢慢体验![image](https://github.com/z2p/sweetPotato/blob/main/picture/show.gif)

<a name="xy0so"></a>
# 安装方法
<a name="hErYN"></a>
1. 使用idea将源代码进行编译安装 或者 直接用release中提供编译好的文件
2. 编译完成后，在jar同目录下将resources目录放在同级，jar在burpsuite启动时，会去加载对应的配置文件进行使用
# 注意事项
1. 新版本的bp需要在首页关闭忽略重复访问检测的功能，否则会影响实际效果

![image.png](https://github.com/z2p/sweetPotato/blob/main/picture/pic2.png)
<a name="VhTgx"></a>

# 参考
1. 部分公共代码（如：iconhash计算）参考了项目 https://github.com/bit4woo/domain_hunter_pro

# 赞赏
创作和开源不易，如果工具帮助到了你，可以打赏一下以资鼓励:)
![](https://github.com/z2p/sweetPotato/blob/main/picture/pic3.png)

# star趋势
[![Stargazers over time](https://starchart.cc/z2p/sweetPotato.svg)](https://starchart.cc/z2p/sweetPotato)
