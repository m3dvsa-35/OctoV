import type { InstructionData } from "../api/types";
import { hex, tokenizeOperands } from "../lib/format";

const TOKEN_CLASS = {
  keyword: "text-muted",
  register: "text-fg",
  number: "text-asm-number",
  punct: "text-faint",
  symbol: "text-fg",
} as const;

/** One instruction: mnemonic + coloured operands; direct targets are links. */
export function AsmText({
  insn,
  onFollow,
}: {
  insn: InstructionData;
  onFollow?: (target: number) => void;
}) {
  const isFlow = /^(?:j|call|loop|ret)/.test(insn.mnemonic.split(" ").at(-1) ?? "");
  return (
    <>
      <span className={isFlow ? "text-accent" : "text-asm-mnemonic"}>{insn.mnemonic.padEnd(7)}</span>{" "}
      {insn.target !== null && onFollow ? (
        <button
          type="button"
          onClick={(e) => {
            e.stopPropagation();
            onFollow(insn.target as number);
          }}
          className="cursor-pointer text-asm-number underline decoration-dotted underline-offset-2 hover:decoration-solid"
        >
          {hex(insn.target)}
        </button>
      ) : (
        tokenizeOperands(insn.operands).map((tok, i) => (
          <span key={i} className={TOKEN_CLASS[tok.kind]}>
            {tok.text}
          </span>
        ))
      )}
      {insn.comment && <span className="text-asm-comment"> ; {insn.comment}</span>}
    </>
  );
}
