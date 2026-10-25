import styles from "./Section.module.css";

/** A numbered page section with a title and optional subtitle. */
export default function Section({ id, num, title, subtitle, last = false, children }) {
  return (
    <section id={id} className={last ? styles.sectionLast : styles.section}>
      <div className="container">
        <div className={styles.head}>
          <span className={styles.num}>{num}</span>
          <h2 className={styles.title}>{title}</h2>
        </div>
        {subtitle && <p className={styles.sub}>{subtitle}</p>}
        {children}
      </div>
    </section>
  );
}
