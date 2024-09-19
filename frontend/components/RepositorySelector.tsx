import React, { useState, useEffect } from 'react';
import {
  Dropdown,
  DropdownItem,
  DropdownMenu,
  DropdownTrigger,
  Input,
  Button,
  Spacer,
  Checkbox,
  Spinner,
} from '@nextui-org/react';
import { useAuth } from '../contexts/AuthContext';
import {
  getOrganizationsAndPersonal,
  getRepositories,
  getRepositoryContents,
} from '../services/api';

interface Owner {
  login: string;
  type: 'user' | 'organization';
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

const RepositorySelector: React.FC = () => {
  const { token } = useAuth();
  const [owners, setOwners] = useState<Owner[]>([]);
  const [selectedOwner, setSelectedOwner] = useState<Owner | null>(null);
  const [repositories, setRepositories] = useState<Repository[]>([]);
  const [selectedRepo, setSelectedRepo] = useState<Repository | null>(null);
  const [files, setFiles] = useState<File[]>([]);
  const [selectedFiles, setSelectedFiles] = useState<string[]>([]);
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [isLoading, setIsLoading] = useState<boolean>(false);

  useEffect(() => {
    if (token) {
      getOrganizationsAndPersonal(token).then(setOwners).catch(console.error);
    }
  }, [token]);

  useEffect(() => {
    if (token && selectedOwner) {
      getRepositories(token, selectedOwner.login, selectedOwner.type)
        .then(setRepositories)
        .catch(console.error);
    }
  }, [token, selectedOwner]);

  useEffect(() => {
    console.log('files', files);
  }, [files]);

  useEffect(() => {
    if (token && selectedOwner && selectedRepo) {
      setIsLoading(true);
      getRepositoryContents(token, selectedOwner.login, selectedRepo.name)
        .then(setFiles)
        .catch(console.error)
        .finally(() => setIsLoading(false));
    }
  }, [token, selectedOwner, selectedRepo]);

  const filteredRepos = repositories.filter((repo) =>
    repo.name.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const handleFileSelection = (path: string) => {
    setSelectedFiles((prev) =>
      prev.includes(path) ? prev.filter((f) => f !== path) : [...prev, path]
    );
  };

  const handleImport = () => {
    console.log('Selected files:', selectedFiles);
    // Implement your import logic here
  };
  return (
    <div>
      <h2>Import Git Repository</h2>
      <Dropdown>
        <DropdownTrigger>
          <Button>
            {selectedOwner?.login || 'Select Account/Organization'}
          </Button>
        </DropdownTrigger>
        {/* <Dropdown.Button flat>{selectedOrg || 'Select Organization'}</Dropdown.Button> */}
        <DropdownMenu
          aria-label="Owner selection"
          onAction={(key) => {
            setSelectedOwner(
              owners.find((owner) => owner.login === key) || null
            );
            setSelectedRepo(null);
            setFiles([]);
            setSelectedFiles([]);
          }}
        >
          {owners.map((owner) => (
            <DropdownItem key={owner.login}>
              {owner.login} ({owner.type})
            </DropdownItem>
          ))}
        </DropdownMenu>
      </Dropdown>
      <Spacer y={1} />
      <Input
        isClearable
        variant="bordered"
        placeholder="Search repositories"
        value={searchTerm}
        onChange={(e) => setSearchTerm(e.target.value)}
      />
      <Spacer y={1} />
      {filteredRepos.map((repo) => (
        <div
          key={repo.name}
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            marginBottom: '10px',
          }}
        >
          <div>
            <b>{repo.name}</b>
            <p style={{ fontSize: 'small' }}>
              {new Date(repo.updatedAt).toLocaleDateString()}
            </p>
          </div>
          <Button onClick={() => setSelectedRepo(repo)}>Select</Button>
        </div>
      ))}
      <Spacer y={1} />
      {selectedRepo && (
        <>
          <h3>Solidity Files in {selectedRepo.name}</h3>
          {isLoading ? (
            <Spinner>Fetching files...</Spinner>
          ) : (
            <>
              {files.map((file) => (
                <Checkbox
                  key={file.path}
                  isSelected={selectedFiles.includes(file.path)}
                  onChange={() => handleFileSelection(file.path)}
                >
                  {file.name}
                </Checkbox>
              ))}
              <Spacer y={1} />
              <Button
                onClick={handleImport}
                disabled={selectedFiles.length === 0}
              >
                Import Selected Files
              </Button>
            </>
          )}
        </>
      )}
      <Button>Import Third-Party Git Repository →</Button>
    </div>
  );
};

export default RepositorySelector;
