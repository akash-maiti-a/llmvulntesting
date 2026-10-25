import { appsTable, syntheticTable, triageTable, resultsNote } from "../data/site.js";
import Section from "./Section.jsx";
import Note from "./Note.jsx";
import styles from "./Results.module.css";

function Table({ data }) {
  return (
    <div className={styles.wrap}>
      <table className={styles.table}>
        <caption className={styles.caption}>{data.caption}</caption>
        <thead>
          <tr>
            {data.columns.map((c) => (
              <th key={c}>{c}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {data.rows.map((r, i) => (
            <tr key={i} className={r.highlight ? styles.rowHl : undefined}>
              {r.cells.map((cell, j) => {
                const isNum = j > 0;
                const up = r.up === j;
                const cls = [isNum ? styles.num : "", up ? styles.up : ""]
                  .filter(Boolean)
                  .join(" ");
                return (
                  <td key={j} className={cls || undefined}>
                    {cell}
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default function Results() {
  return (
    <Section
      id="results"
      num="04"
      title="Results"
      subtitle="Triage consistently raises precision while keeping almost all true positives. Numbers below are from results/report.md, model qwen3:8b (Q4_K_M), temperature 0."
    >
      <Table data={appsTable} />
      <Table data={syntheticTable} />
      <Table data={triageTable} />
      <Note
        tone="good"
        mark={resultsNote.mark}
        title={resultsNote.title}
        body={resultsNote.body}
      />
    </Section>
  );
}
