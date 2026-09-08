export function optionValue(args: readonly string[], name: string, required = false): string | undefined {
  const indexes = args.flatMap((value, index) => value === name ? [index] : []);
  if (indexes.length > 1) throw new Error(`${name} 不能重复`);
  const index = indexes[0];
  const value = index === undefined ? undefined : args[index + 1];
  if (index !== undefined && (!value || value.startsWith("--"))) throw new Error(`${name} 缺少参数值`);
  if (required && !value) throw new Error(`缺少必需参数 ${name}`);
  return value;
}
