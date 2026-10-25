import styles from "./Note.module.css";

/** A callout line with a leading mark; `tone` = "neutral" | "good". */
export default function Note({ mark, title, body, tone = "neutral" }) {
  return (
    <div className={tone === "good" ? styles.noteGood : styles.note}>
      <span className={styles.mark}>{mark}</span>
      <div>
        <strong className={styles.strong}>{title}</strong> {body}
      </div>
    </div>
  );
}
