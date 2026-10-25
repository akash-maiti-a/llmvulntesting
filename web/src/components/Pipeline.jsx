import { pipeline } from "../data/site.js";
import Section from "./Section.jsx";
import styles from "./Pipeline.module.css";

function Node({ t, s, hl }) {
  return (
    <div className={hl ? `${styles.node} ${styles.nodeHl}` : styles.node}>
      <div className={styles.t}>{t}</div>
      <div className={styles.s}>{s}</div>
    </div>
  );
}

export default function Pipeline() {
  return (
    <Section
      id="pipeline"
      num="02"
      title="The pipeline"
      subtitle="One command runs the whole chain: fetch pinned target sources, scan with every engine, normalize the findings, triage them with the LLM, and evaluate against ground truth into a report."
    >
      <div className={styles.pipe}>
        {pipeline.rows.map((row, i) => {
          if (row.kind === "down") {
            return (
              <div key={i} className={styles.row}>
                <span className={styles.arrowV}>→</span>
              </div>
            );
          }
          if (row.kind === "fan") {
            return (
              <div key={i} className={styles.row}>
                <div className={styles.fan}>
                  {row.nodes.map((n) => (
                    <Node key={n.t} {...n} />
                  ))}
                </div>
              </div>
            );
          }
          return (
            <div key={i} className={styles.row}>
              {row.nodes.map((n, j) => (
                <span key={n.t} className={styles.flowItem}>
                  {j > 0 && <span className={styles.arrow}>→</span>}
                  <Node {...n} />
                </span>
              ))}
            </div>
          );
        })}
        <div className={styles.cap}>{pipeline.caption}</div>
      </div>
    </Section>
  );
}
