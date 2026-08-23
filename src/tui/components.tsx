import { Box, Text, useInput } from "ink";
import { useState, useEffect } from "react";

export const dim = (s: string) => s; // styling done via <Text dimColor>

export function Header({ title, hint }: { title: string; hint?: string }) {
  return (
    <Box marginBottom={1} flexDirection="column">
      <Text bold color="magenta">✦ abracadabra</Text>
      <Text bold>{title}</Text>
      {hint ? <Text dimColor>{hint}</Text> : null}
    </Box>
  );
}

interface SelectItem {
  label: string;
  value: string;
  hint?: string;
}

export function SelectList({
  items,
  onSelect,
  onHighlight,
}: {
  items: SelectItem[];
  onSelect: (value: string) => void;
  onHighlight?: (value: string) => void;
}) {
  const [index, setIndex] = useState(0);

  useInput((_input, key) => {
    if (key.upArrow || _input === "k") {
      setIndex((i) => Math.max(0, i - 1));
    } else if (key.downArrow || _input === "j") {
      setIndex((i) => Math.min(items.length - 1, i + 1));
    } else if (key.return) {
      if (items[index]) onSelect(items[index].value);
    }
  });

  const current = items[index];
  useEffect(() => {
    if (current && onHighlight) onHighlight(current.value);
  }, [current?.value]); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <Box flexDirection="column">
      {items.map((item, i) => (
        <Box key={item.value}>
          <Text color={i === index ? "magenta" : undefined}>
            {i === index ? "❯ " : "  "}
            {item.label}
          </Text>
          {item.hint ? <Text dimColor> {item.hint}</Text> : null}
        </Box>
      ))}
    </Box>
  );
}

export function TextInput({
  value,
  onChange,
  placeholder,
  mask = false,
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  mask?: boolean;
}) {
  useInput((input, key) => {
    if (key.backspace || key.delete) {
      onChange(value.slice(0, -1));
    } else if (
      input &&
      !key.upArrow &&
      !key.downArrow &&
      !key.leftArrow &&
      !key.rightArrow &&
      !key.tab
    ) {
      onChange(value + input);
    }
  });

  return (
    <Text>
      {value.length === 0 && placeholder ? (
        <Text dimColor>{placeholder}</Text>
      ) : mask ? (
        "•".repeat(value.length)
      ) : (
        value
      )}
      <Text inverse>{"\u00A0"}</Text>
    </Text>
  );
}

export interface InputRequest {
  title: string;
  initial?: string;
  mask?: boolean;
  onSubmit: (value: string) => void | Promise<void>;
  onCancel: () => void;
}

export function InputView({ request }: { request: InputRequest }) {
  const [value, setValue] = useState(request.initial ?? "");

  useInput((_input, key) => {
    if (key.escape) {
      request.onCancel();
    } else if (key.return) {
      void request.onSubmit(value);
    }
  });

  return (
    <Box flexDirection="column">
      <Header title={request.title} hint="enter to confirm · esc to cancel" />
      <Box>
        <Text>{request.mask ? "" : "> "}</Text>
        <TextInput
          value={value}
          onChange={setValue}
          mask={request.mask}
          placeholder="type a value…"
        />
      </Box>
    </Box>
  );
}

export function ConfirmView({
  message,
  onConfirm,
  onCancel,
}: {
  message: string;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  useInput((input, key) => {
    if (input?.toLowerCase() === "y") onConfirm();
    else if (key.escape || input?.toLowerCase() === "n") onCancel();
  });
  return (
    <Box flexDirection="column">
      <Header title={message} hint="y = yes · n/esc = no" />
    </Box>
  );
}
