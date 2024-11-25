import { useState, type FC } from "react";

import { Copy, Check } from "lucide-react";
import ReactMarkdown from "react-markdown";
import { Prism as SyntaxHighlighter } from "react-syntax-highlighter";
import { vscDarkPlus } from "react-syntax-highlighter/dist/cjs/styles/prism";

interface MarkdownWithCodeProps {
  content: string;
  className?: string;
}

const CodeBlock = ({ language, children }: { language: string; children: string }) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(children);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="relative">
      <button
        onClick={handleCopy}
        className="absolute right-2 top-2 p-2 rounded-lg bg-gray-800 hover:bg-gray-700 transition-colors"
      >
        {copied ? <Check size={16} className="text-green-500" /> : <Copy size={16} className="text-gray-400" />}
      </button>
      <SyntaxHighlighter
        style={vscDarkPlus}
        language={language}
        PreTag="div"
        customStyle={{
          background: "#0C0C0C",
          padding: "1rem",
          borderRadius: "0.5rem",
        }}
      >
        {children}
      </SyntaxHighlighter>
    </div>
  );
};

const MarkdownWithCode: FC<MarkdownWithCodeProps> = ({
  content,
  className = "text-sm font-normal text-[#D4D4D8] mb-2 px-3",
}) => {
  return (
    <ReactMarkdown
      className={className}
      components={{
        code: ({ className, children, ...props }) => {
          const match = /language-(\w+)/.exec(className || "");
          return match ? (
            <CodeBlock language={match[1]}>{String(children).replace(/\n$/, "")}</CodeBlock>
          ) : (
            <code className="bg-[#1E1E1E] text-[#D4D4D8] px-1 py-0.5 rounded text-sm font-mono" {...props}>
              {children}
            </code>
          );
        },
        ol: ({ children }) => <ol className="list-decimal pl-6 space-y-2 mb-4">{children}</ol>,
        ul: ({ children }) => <ul className="list-disc pl-6 space-y-2 mb-4">{children}</ul>,
        li: ({ children }) => <li className="text-[#D4D4D8] leading-relaxed">{children}</li>,
        p: ({ children }) => <p className="mb-4 leading-relaxed">{children}</p>,
        h1: ({ children }) => <h1 className="text-2xl font-bold mb-4 text-white">{children}</h1>,
        h2: ({ children }) => <h2 className="text-xl font-bold mb-3 text-white">{children}</h2>,
        h3: ({ children }) => <h3 className="text-lg font-bold mb-2 text-white">{children}</h3>,
        blockquote: ({ children }) => (
          <blockquote className="border-l-4 border-gray-600 pl-4 my-4 italic">{children}</blockquote>
        ),
        em: ({ children }) => <em className="italic">{children}</em>,
        strong: ({ children }) => <strong className="font-semibold text-white">{children}</strong>,
        table: ({ children }) => (
          <div className="overflow-x-auto mb-4">
            <table className="min-w-full divide-y divide-gray-700">{children}</table>
          </div>
        ),
        thead: ({ children }) => <thead className="bg-[#1E1E1E]">{children}</thead>,
        tbody: ({ children }) => <tbody className="divide-y divide-gray-700">{children}</tbody>,
        tr: ({ children }) => <tr className="hover:bg-[#1E1E1E]">{children}</tr>,
        th: ({ children }) => <th className="px-4 py-2 text-left text-white font-semibold">{children}</th>,
        td: ({ children }) => <td className="px-4 py-2">{children}</td>,
      }}
    >
      {content}
    </ReactMarkdown>
  );
};

export default MarkdownWithCode;
