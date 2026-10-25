import styles from "./Card.module.css";

/** Grid wrapper; `cols` is 2 or 3. */
export function CardGrid({ cols = 3, children }) {
  return (
    <div className={cols === 2 ? styles.grid2 : styles.grid3}>{children}</div>
  );
}

/** A single content card with an uppercase tag, heading, and body. */
export default function Card({ tag, title, body }) {
  return (
    <article className={styles.card}>
      {tag && <div className={styles.tag}>{tag}</div>}
      <h3 className={styles.title}>{title}</h3>
      <p className={styles.body}>{body}</p>
    </article>
  );
}
