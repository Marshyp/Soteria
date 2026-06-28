export function MetricCard({label, value}: {label: string; value: string | number}) {
  return <div className="card"><p>{label}</p><h2>{value}</h2></div>;
}
