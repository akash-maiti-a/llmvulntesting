import { methodCards, methodNote } from "../data/site.js";
import Section from "./Section.jsx";
import Card, { CardGrid } from "./Card.jsx";
import Note from "./Note.jsx";

export default function Method() {
  return (
    <Section
      id="method"
      num="03"
      title="How it works"
      subtitle="Six stages, each a small, testable module."
    >
      <CardGrid cols={2}>
        {methodCards.map((c) => (
          <Card key={c.title} tag={c.tag} title={c.title} body={c.body} />
        ))}
      </CardGrid>
      <Note mark={methodNote.mark} title={methodNote.title} body={methodNote.body} />
    </Section>
  );
}
