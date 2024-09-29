interface Owner {
  login: string;
  type: "user" | "organization";
}

interface Repository {
  name: string;
  updatedAt: string;
}

interface File {
  name: string;
  path: string;
  type: string;
  download_url: string;
}
