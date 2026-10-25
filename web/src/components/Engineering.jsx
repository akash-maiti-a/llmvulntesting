import { engineeringPoints, runSnippet } from "../data/site.js";
import Section from "./Section.jsx";
import styles from "./Engineering.module.css";

export default function Engineering() {
  return (
    <Section
      id="stack"
      num="06"
      title="Engineering notes"
      subtitle="Choices made so the results are trustworthy and the project is easy to run."
      last
    >
      <ul className={styles.list}>
        {engineeringPoints.map((p) => (
          <li key={p.strong}>
            <strong>{p.strong}</strong>
            {p.rest}
          </li>
        ))}
      </ul>

      <h3 className={styles.runHead}>RUN IT YOURSELF</h3>
      <pre className={styles.pre}>
        <code>{runSnippet}</code>
      </pre>
    </Section>
  );
}
