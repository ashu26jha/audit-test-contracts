export function openFeedbackEmail(subject: string, body: string) {
  const encodedSubject = encodeURIComponent(subject);
  const encodedBody = encodeURIComponent(body);
  const mailtoLink = `mailto:auditagent@nethermind.io?subject=${encodedSubject}&body=${encodedBody}`;

  // Try to open the mailto link
  const mailtoWindow = window.open(mailtoLink, "_blank");

  // If the window is null or undefined, it means the mailto link didn't work
  if (!mailtoWindow || mailtoWindow.closed || typeof mailtoWindow.closed === "undefined") {
    // Fallback: Navigate to the contact page
    window.location.href = "https://auditagent.nethermind.io/contact-us";
  }
}
