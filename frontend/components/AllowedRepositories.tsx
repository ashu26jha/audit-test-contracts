import React from "react";

import { Card, CardBody, CircularProgress, Button, Image } from "@nextui-org/react";

import { SERVICES } from "@/config/constants";
import { useAllowedRepositories } from "@/hooks/useAllowedRepositories";

const AllowedRepositories: React.FC = () => {
  const { repositories, loading, error } = useAllowedRepositories();

  console.log(repositories);

  if (loading) {
    return (
      <div className="w-full flex justify-center items-center p-8">
        <CircularProgress size="lg" color="secondary" />
      </div>
    );
  }

  if (error) {
    return <div className="w-full p-8 text-center text-danger">{error}</div>;
  }

  return (
    <div className="w-1/3 p-4">
      <h3 className="font-inter font-medium text-[16px] text-[#D4D4D8] leading-[24px] mb-4">Allowed Repositories</h3>
      <div className="text-sm font-normal text-[#A1A1AA] mb-4">
        These are the repositories that you allowed via Github.
      </div>

      {repositories.length > 0 && repositories[0].all_repos_access && (
        <div className="text-sm font-normal text-[#A1A1AA] mb-4">You have full access to all repositories.</div>
      )}

      {repositories.length > 0 ? (
        <Card className="w-full max-h-[500px] min-h-[400px] overflow-y-auto border border-[#27272A] bg-[#18181B]">
          <CardBody>
            {repositories.map((repo) => (
              <div key={repo.name} className="flex items-center justify-between p-1 rounded-md">
                <div className="flex items-center gap-2">
                  <Image src="/repo-avatar.svg" alt="Repository" width={24} height={24} />
                  <span className="text-sm font-normal text-[#A1A1AA]">{repo.name}</span>
                  {repo.private && (
                    <Image src="/private.svg" alt="Private" width={16} height={16} style={{ color: "#A1A1AA" }} />
                  )}
                </div>
              </div>
            ))}
          </CardBody>
        </Card>
      ) : (
        <Card className="w-full min-h-[400px] border border-[#27272A] bg-[#18181B] flex items-center justify-center">
          <CardBody className="flex flex-col items-center justify-center text-center">
            <Image src="/empty_repository.svg" alt="No repositories" width={55} height={55} className="mb-4" />
            <p className="text-sm text-[#A1A1AA]">
              No allowed repositories.
              <br />
              Please add from below.
            </p>
          </CardBody>
        </Card>
      )}

      <Button
        className="mt-4 w-full bg-[#27272a] border border-[#3F3F46] hover:bg-[#3F3F46]"
        onClick={() => window.open(SERVICES.GITHUB_APP_URL, "_blank")}
      >
        Manage Repos on GitHub
        <Image
          src="/link.svg"
          alt="External Link"
          width={14}
          height={14}
          className="ml-2"
          style={{ color: "#A1A1AA" }}
        />
      </Button>
    </div>
  );
};

export default AllowedRepositories;
