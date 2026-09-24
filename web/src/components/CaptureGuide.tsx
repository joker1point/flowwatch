import { useState } from 'react'
import { retryCapture } from '../api'

interface Props {
  /** `/api/health` 的 error 原文：**如实展示**，不替产品改写原因 */
  error: string
  /** 重试后让 App 立刻刷新一次 health（否则要等 5 秒轮询才看到变化） */
  onRefresh: () => void
}

// 直链指向**当前版本**的官方安装包（版本号取自 npcap.com 首页 property="softwareVersion"；
// 2026-09-24 核对 = 1.89，实测 HTTP 200 / 1.26 MB）。版本更新后改这一行即可 ——
// 之所以不每次联网去查最新版：本工具的原则是"不主动出站"，这条也写进了 README 的许可说明。
const NPCAP_INSTALLER = 'https://npcap.com/dist/npcap-1.89.exe'
// 官网页留作次级入口：直链失效、或用户想要别的版本时用
const NPCAP_PAGE = 'https://npcap.com/#download'

/**
 * 首启引导：机器缺抓包驱动（实际最常见的就是没装 Npcap）时，把
 * 「为什么没有数据 / 要我做什么」讲成三步，并给一个「重新检测」按钮。
 *
 * 关键点：装完驱动**不必重启程序** —— 后端 `Capturer.pcap` 是懒加载的，
 * `/api/capture/retry` 会在进程内重新加载 wpcap.dll（2026-09-23 起）。
 */
export function CaptureGuide({ error, onRefresh }: Props) {
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState<string | null>(null)

  const retry = async () => {
    setBusy(true)
    setResult(null)
    try {
      const data = await retryCapture()
      if (data.ok) {
        // 成功时**先让这句话真的被看见**再刷新 health：刷新后 error 变 null，
        // 引导块会整体卸载（React 18 会把两次 setState 批在一起渲染，否则这句一闪都没有）
        setResult(data.already ? '采集本来就在运行。' : '成功了：已开始采集，数据马上会出来。')
        window.setTimeout(onRefresh, 900)
        return
      }
      setResult(`还是没检测到驱动：${data.error ?? '未知原因'}`)
      onRefresh()
    } catch (exc) {
      setResult(exc instanceof Error ? exc.message : String(exc))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="guide" role="status">
      <div className="guide__head">
        <b>未启用采集：这台机器还没有抓包驱动</b>
        <span className="guide__why">{error}</span>
      </div>

      <ol className="guide__steps">
        <li>
          点下面第一个链接下载安装 <b>Npcap</b>（Windows 抓包驱动，装一次即可）：向导保持默认
          （不用勾 WinPcap 兼容模式），Windows 会要一次<b>管理员授权</b>，允许即可
        </li>
        <li>装完<b>不用重启电脑</b>，也不用重启本程序</li>
        <li>回到这里点「我已装好，重新检测」</li>
      </ol>

      <div className="guide__actions">
        <a className="guide__link" href={NPCAP_INSTALLER} target="_blank" rel="noreferrer">
          下载 Npcap 1.89 安装包（1.3 MB）
        </a>
        <a
          className="guide__link guide__link--minor"
          href={NPCAP_PAGE}
          target="_blank"
          rel="noreferrer"
        >
          官网页面（换版本 / 直链失效时用）
        </a>
        <button type="button" className="guide__cta" onClick={retry} disabled={busy}>
          {busy ? '检测中…（要逐张网卡试抓，约几秒）' : '我已装好，重新检测'}
        </button>
        {result ? <span className="guide__result">{result}</span> : null}
      </div>

      <p className="guide__foot">
        为什么不能替你装好：Npcap 是 Nmap 项目的第三方驱动，免费版许可不允许随其他软件一起分发
        （见 README《没装 Npcap 时会发生什么》）。仍然检测不到时：关掉本程序重新双击一次
        （个别机器上驱动服务要稍后才起来）；在这之前，界面、历史库与流量助手都照常可用。
      </p>
    </div>
  )
}
