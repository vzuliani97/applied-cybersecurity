// A small IAM policy evaluator, following the rules AWS documents for a
// request inside one account:
//   1. An explicit Deny in any policy wins.
//   2. Otherwise an Allow in the identity policy OR the resource policy grants.
//   3. Otherwise the request is implicitly denied.
// Only the pieces this lab needs are implemented: wildcards in Action and
// Resource, and the StringEquals / StringNotEquals / DateLessThan operators.

export interface Statement {
  Sid?: string;
  Effect: "Allow" | "Deny";
  Action: string | string[];
  Resource: string | string[];
  Condition?: Partial<Record<"StringEquals" | "StringNotEquals" | "DateLessThan", Record<string, string>>>;
}

export interface Policy {
  name: string;
  Statement: Statement[];
}

/** Request context keys the conditions can look at. A missing key is undefined. */
export type Context = Partial<Record<"aws:SourceVpce" | "aws:TokenIssueTime" | "aws:SourceIp", string>>;

export interface Decision {
  allowed: boolean;
  reason: "explicit-deny" | "allow" | "implicit-deny";
  /** The statement that decided, as "policy/Sid". */
  by?: string;
}

const list = (v: string | string[]) => (Array.isArray(v) ? v : [v]);

/** IAM wildcards: * matches any run of characters, ? exactly one. Case-insensitive for actions. */
export function wildcard(pattern: string, value: string, ignoreCase = false): boolean {
  const re = new RegExp("^" + pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".") + "$", ignoreCase ? "i" : "");
  return re.test(value);
}

function conditionsHold(st: Statement, ctx: Context): boolean {
  for (const [op, pairs] of Object.entries(st.Condition ?? {})) {
    for (const [key, expected] of Object.entries(pairs ?? {})) {
      const actual = ctx[key as keyof Context];
      if (op === "StringEquals" && actual !== expected) return false;
      // Negated operators match when the key is missing, as in AWS. That is
      // what makes "deny unless the request came through our VPC endpoint" work
      // for a request from the internet, which carries no endpoint at all.
      if (op === "StringNotEquals" && actual === expected) return false;
      if (op === "DateLessThan" && !(actual !== undefined && Date.parse(actual) < Date.parse(expected))) return false;
    }
  }
  return true;
}

function matches(st: Statement, action: string, resource: string, ctx: Context): boolean {
  return (
    list(st.Action).some((a) => wildcard(a, action, true)) &&
    list(st.Resource).some((r) => wildcard(r, resource)) &&
    conditionsHold(st, ctx)
  );
}

export function evaluate(identity: Policy[], resourcePolicy: Policy | null, action: string, resource: string, ctx: Context): Decision {
  const all = [...identity, ...(resourcePolicy ? [resourcePolicy] : [])];
  for (const p of all) for (const st of p.Statement) if (st.Effect === "Deny" && matches(st, action, resource, ctx)) return { allowed: false, reason: "explicit-deny", by: `${p.name}/${st.Sid ?? "?"}` };
  for (const p of all) for (const st of p.Statement) if (st.Effect === "Allow" && matches(st, action, resource, ctx)) return { allowed: true, reason: "allow", by: `${p.name}/${st.Sid ?? "?"}` };
  return { allowed: false, reason: "implicit-deny" };
}
