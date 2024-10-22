export {};

declare global {
  interface Window {
    _paq: Array<["trackPageView"] | ["enableLinkTracking"] | [string, any]>;
  }
}
