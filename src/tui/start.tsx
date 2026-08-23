import { render } from "ink";
import { App } from "./App.js";

export function startTui(): void {
  render(<App />, { exitOnCtrlC: true });
}
