import { ApprovalRecords } from "@/components/approval-records";

export default function ApprovalsPage() {
  // MainContent already applies the page padding; this wrapper only constrains width.
  return (
    <div className="flex min-w-0 flex-1 flex-col">
      <ApprovalRecords />
    </div>
  );
}
