export function openFeedbackEmail(subject: string, body: string) {
  const encodedSubject = encodeURIComponent(subject);
  const encodedBody = encodeURIComponent(body);
  const mailtoLink = `mailto:kirill.balakhonov@nethermind.io?subject=${encodedSubject}&body=${encodedBody}`;
  window.location.href = mailtoLink;
}
