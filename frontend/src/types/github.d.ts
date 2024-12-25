interface Owner {
  login: string;
  type: "user" | "organization";
}

interface Repository {
  name: string;
  updatedAt: string;
  private: boolean;
  all_repos_access?: boolean;
}

interface Branch {
  name: string;
  isDefault: boolean;
}

interface SolidityFile {
  name: string;
  path: string;
  type: string;
  download_url: string;
  lineCount: number;
  token: number;
}

interface ReadmeFile {
  name: string;
  path: string;
  type: string;
  download_url: string;
  character_count: number;
  token: number;
}

interface RepoDocs {
  readme: string[];
  qa: Record<string, string>;
}
