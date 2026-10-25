import Nav from "./components/Nav.jsx";
import Hero from "./components/Hero.jsx";
import Overview from "./components/Overview.jsx";
import Pipeline from "./components/Pipeline.jsx";
import Method from "./components/Method.jsx";
import Results from "./components/Results.jsx";
import FineTuning from "./components/FineTuning.jsx";
import Engineering from "./components/Engineering.jsx";
import Footer from "./components/Footer.jsx";

export default function App() {
  return (
    <>
      <Nav />
      <main>
        <Hero />
        <Overview />
        <Pipeline />
        <Method />
        <Results />
        <FineTuning />
        <Engineering />
      </main>
      <Footer />
    </>
  );
}
