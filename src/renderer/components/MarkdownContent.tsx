import ReactMarkdown, { type Components } from "react-markdown";
import remarkGfm from "remark-gfm";

const components: Components = {
  a: ({ node: _node, href, children, ...props }) => <a
    {...props}
    href={href}
    rel="noreferrer"
    title={href ? `外部导航已禁用：${href}` : undefined}
    onClick={(event) => event.preventDefault()}
  >{children}</a>,
  img: ({ node: _node, alt }) => <span className="markdown-image-placeholder">[图片已阻止加载{alt ? `：${alt}` : ""}]</span>,
  table: ({ node: _node, ...props }) => <div className="markdown-table-wrap"><table {...props} /></div>,
};

export function MarkdownContent({ text, className = "" }: { text: string; className?: string }) {
  return <div className={`markdown-content ${className}`.trim()}>
    <ReactMarkdown remarkPlugins={[remarkGfm]} skipHtml components={components}>{text}</ReactMarkdown>
  </div>;
}
