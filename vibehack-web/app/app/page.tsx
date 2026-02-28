import { redirect } from "next/navigation";

export default function AppHomePage() {
  redirect("/app/scans");
}
