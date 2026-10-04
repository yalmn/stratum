import { Button } from "../../components/ui/Button";
import { Field, Input, Select, Textarea } from "../../components/ui/Input";
import { useEditCase } from "../../lib/api/queries";
import type { Case } from "../../lib/api/types";

export function EditCase({ value, onClose }: { value: Case; onClose: () => void }) {
  const edit = useEditCase(value.case_number);
  return (
    <form className="inline-panel" onSubmit={(event) => {
      event.preventDefault();
      const form = new FormData(event.currentTarget);
      const d: Record<string, string | null> = {};
      for (const name of ["titel", "beschreibung", "ordner", "einstufung", "status"]) {
        const text = String(form.get(name) ?? "").trim();
        d[name] = text || null;
      }
      edit.mutate(d, { onSuccess: onClose });
    }}>
      <h2>Edit case {value.case_number}</h2>
      <div className="form-grid">
        <Field label="Title"><Input name="titel" required defaultValue={value.title} autoFocus /></Field>
        <Field label="Status">
          <Select name="status" defaultValue={value.status}>
            <option value="new">New</option><option value="active">Active</option>
            <option value="review">Review</option><option value="suspended">Suspended</option>
            <option value="closed">Closed</option><option value="archived">Archived</option>
            <option value="retained">Asservat</option>
          </Select>
        </Field>
        <Field label="Case folder on the server" hint="Use an existing absolute VM path. Existing evidence paths stay unchanged.">
          <Input name="ordner" mono defaultValue={value.case_folder ?? ""} placeholder="/mnt/evidence/m57_jean_scenario_v2" />
        </Field>
        <Field label="Classification">
          <Select name="einstufung" defaultValue={value.classification}>
            <option value="open">Open</option><option value="internal">Internal</option>
            <option value="confidential">Confidential</option><option value="strictly_confidential">Strictly confidential</option>
          </Select>
        </Field>
        <Field label="Description" wide><Textarea name="beschreibung" rows={2} defaultValue={value.description ?? ""} /></Field>
      </div>
      <p className="muted">Asservat hides the case from the default case list. Evidence, results and audit remain stored; change the status to show it again.</p>
      {edit.error && <div className="form-error">{edit.error.message}</div>}
      <div className="form-actions">
        <Button type="submit" variant="primary" disabled={edit.isPending}>{edit.isPending ? "Saving…" : "Save changes"}</Button>
        <Button onClick={onClose} disabled={edit.isPending}>Cancel</Button>
      </div>
    </form>
  );
}
