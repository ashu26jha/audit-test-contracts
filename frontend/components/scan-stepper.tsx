import React, { useState, useEffect } from 'react';
import {
  Button,
  Checkbox,
  Input,
  Table,
  TableHeader,
  TableColumn,
  TableBody,
  TableRow,
  TableCell,
  Select,
  SelectItem,
  Spinner,
  Card,
  CardHeader,
  CardBody,
} from '@nextui-org/react';
import { Autocomplete, AutocompleteItem } from '@nextui-org/autocomplete';
import {
  Home,
  GitBranch,
  FileCode,
  FolderIcon,
  Search,
  FileIcon,
} from 'lucide-react';
import { useRouter } from 'next/navigation';
import { useAuth } from '../contexts/AuthContext';
import { ArrowRight } from 'lucide-react';
import {
  getOrganizationsAndPersonal,
  getRepositories,
  getRepositoryContents,
  getBranches,
} from '../services/api';
import api from '../services/api';

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

const ScanStepper: React.FC = () => {
  const router = useRouter();
  const [currentStep, setCurrentStep] = useState(1);
  const [selectedOrg, setSelectedOrg] = useState('');
  // const [selectedRepo, setSelectedRepo] = useState('');
  const [selectedBranch, setSelectedBranch] = useState('');
  const [selectedContracts, setSelectedContracts] = useState<string[]>([]);
  const [isNextEnabled, setIsNextEnabled] = useState(false);
  const [branchSearch, setBranchSearch] = useState('');
  const [contractSearch, setContractSearch] = useState('');

  const { token } = useAuth();
  const [owners, setOwners] = useState<Owner[]>([]);
  const [selectedOwner, setSelectedOwner] = useState<Owner | null>(null);
  const [repositories, setRepositories] = useState<Repository[]>([]);
  const [selectedRepo, setSelectedRepo] = useState<Repository | null>(null);
  const [files, setFiles] = useState<File[]>([]);
  const [selectedFiles, setSelectedFiles] = useState<string[]>([]);
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [branches, setBranches] = useState<string[]>([]);
  const [solidityFiles, setSolidityFiles] = useState<File[]>([]);

  const steps = [
    { icon: <Home size={24} />, label: 'Repository' },
    { icon: <GitBranch size={24} />, label: 'Branch' },
    { icon: <FileCode size={24} />, label: 'Contract' },
  ];

  useEffect(() => {
    setIsNextEnabled(
      (currentStep === 1 && selectedOwner !== null && selectedRepo !== null) ||
        (currentStep === 2 && selectedBranch !== '') ||
        (currentStep === 3 && selectedContracts.length > 0)
    );
  }, [
    currentStep,
    selectedOrg,
    selectedRepo,
    selectedBranch,
    selectedContracts,
  ]);

  const handleScan = async () => {
    if (currentStep === steps.length) {
      setIsLoading(true);
      try {
        const response = await api.post(
          '/api/v1/audit-agent',
          {
            repositoryURL: `https://github.com/${selectedOwner?.login}/${selectedRepo?.name}`,
            contractFiles: selectedContracts,
          },
          {
            headers: {
              Authorization: `Bearer ${token}`,
            },
          }
        );

        console.log('Scan initiated:', response.data);
        // Navigate to the scan results page with the scan ID
        router.push(`/scan-results/${response.data.data.scan_id}`);
      } catch (error) {
        console.error('Error initiating scan:', error);
        // Handle error (e.g., show an error message to the user)
      } finally {
        setIsLoading(false);
      }
    } else {
      handleNext();
    }
  };

  const handleNext = () => {
    if (currentStep < steps.length) {
      setCurrentStep(currentStep + 1);
    } else {
      // Handle scan initiation
      setIsLoading(true);
      // Simulating an API call or processing time
      setTimeout(() => {
        setIsLoading(false);
        console.log('Scan completed for contracts:', selectedContracts);
        // Navigate to the scan results page
        router.push('/scan-results');
      }, 3000); // Adjust the timeout as needed
    }
  };

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

  console.log('repositories', repositories);

  useEffect(() => {
    console.log('files', files);
  }, [files]);

  useEffect(() => {
    if (token && selectedOwner && selectedRepo) {
      getBranches(token, selectedOwner.login, selectedRepo.name)
        .then(setBranches)
        .catch(console.error);
    }
  }, [token, selectedOwner, selectedRepo]);

  useEffect(() => {
    console.log('selectedBranch-', selectedBranch);
    console.log('selectedOwner', selectedOwner);
    console.log('selectedRepo', selectedRepo);
    console.log('token', token);
    if (token && selectedOwner && selectedRepo && selectedBranch) {
      getRepositoryContents(
        token,
        selectedOwner.login,
        selectedRepo.name,
        selectedBranch
      )
        .then(setSolidityFiles)
        .catch(console.error);
    }
  }, [token, selectedOwner, selectedRepo, selectedBranch]);

  if (isLoading) {
    return (
      <div className="min-h-screen bg-black text-white flex flex-col items-center justify-center">
        <div className="bg-[#222222] rounded-lg p-8 flex flex-col items-center">
          <Spinner size="lg" color="secondary" />
          <p className="mt-4 text-lg font-semibold">Loading</p>
          <p className="mt-2 text-sm text-gray-400">
            Please wait while we analyze your code.
          </p>
        </div>
      </div>
    );
  }

  const handleBack = () => {
    if (currentStep > 1) {
      setCurrentStep(currentStep - 1);
    } else {
      router.push('/dashboard');
    }
  };

  return (
    // <div className="min-h-screen bg-black text-white flex flex-col">
    <Card className="w-full min-h-screen flex flex-col">
      {/* Breadcrumb and Back/Next buttons */}
      {/* <div className="bg-[#111111] p-4 flex justify-between items-center border-t border-b border-gray-800"> */}
      <CardHeader className=" p-4 flex justify-between items-center border-t border-b border-gray-800">
        <div className="text-sm text-gray-400">Dashboard / Scan Code</div>
        <div>
          <Button
            className="mr-2"
            onClick={handleBack}
            disabled={currentStep === 1}
          >
            Go Back
          </Button>
          <Button
            color="secondary"
            className="bg-[#8B5CF6]"
            disabled={!isNextEnabled}
            endContent={<ArrowRight size={20} />}
            onClick={handleScan}
          >
            {currentStep === steps.length ? 'Scan Code' : 'Next'}
          </Button>
        </div>
      </CardHeader>

      {/* Main content */}
      <main className="flex-grow p-8">
        {/* Stepper */}
        <div className="flex justify-center mb-12">
          {steps.map((step, index) => (
            <div key={step.label} className="flex items-center">
              <div
                className={`w-12 h-12 rounded-full flex items-center justify-center ${
                  index + 1 === currentStep ? 'bg-[#8B5CF6]' : 'bg-gray-700'
                }`}
              >
                {step.icon}
              </div>
              <span className="mx-2 text-sm">{step.label}</span>
              {index < steps.length - 1 && (
                <div className="w-16 h-px bg-gray-700 mx-2" />
              )}
            </div>
          ))}
        </div>

        {/* Form */}
        <div className="max-w-3xl mx-auto">
          {currentStep === 1 && (
            <>
              <div className="mb-6">
                <Select
                  label={
                    <>
                      Git Organization
                      <span style={{ color: 'red', marginLeft: '4px' }}>*</span>
                    </>
                  }
                  placeholder="Select an organization"
                  labelPlacement="outside"
                  className="w-full"
                  onSelectionChange={(keys) => {
                    // const selected = Array.from(keys)[0] as string;
                    const selected = Array.from(keys)[0] as string;
                    // setSelectedOrg(selected);
                    setSelectedOwner(
                      owners.find((owner) => owner.login === selected) || null
                    );
                    setSelectedRepo(null);
                    setFiles([]);
                    setSelectedFiles([]);
                  }}
                >
                  {owners.map((org) => (
                    <SelectItem key={org.login} value={org.login}>
                      {org.login}
                    </SelectItem>
                  ))}
                </Select>
              </div>
              {selectedOwner ? (
                <div className="mb-6">
                  <Autocomplete
                    label={
                      <>
                        Git Repository
                        <span style={{ color: 'red', marginLeft: '4px' }}>
                          *
                        </span>
                      </>
                    }
                    labelPlacement="outside"
                    placeholder="Search a repository"
                    className="w-full"
                    onSelectionChange={(key) => {
                      const selected = key as string;
                      setSelectedRepo(
                        repositories.find((repo) => repo.name === selected) ||
                          null
                      );
                    }}
                  >
                    {repositories.map((repo) => (
                      <AutocompleteItem key={repo.name} value={repo.name}>
                        {repo.name}
                      </AutocompleteItem>
                    ))}
                  </Autocomplete>
                </div>
              ) : (
                <div className="mb-6">
                  <label className="block text-sm font-medium mb-2">
                    Git Repository
                  </label>
                  <div className="bg-[#222222] rounded p-8 flex flex-col items-center justify-center text-center">
                    <Home size={24} className="mb-2" />
                    <p className="text-sm text-gray-400">
                      Repository would appear here,
                      <br />
                      after selecting the organization.
                    </p>
                  </div>
                </div>
              )}
            </>
          )}

          {currentStep === 2 && (
            <div className="mb-6">
              <Autocomplete
                label="Select Branch"
                labelPlacement="outside"
                placeholder="Search branch"
                className="w-full"
                onSelectionChange={(keys) => {
                  const selected = keys as string;
                  setSelectedBranch(selected);
                }}
              >
                {branches.map((branch) => (
                  <AutocompleteItem key={branch} value={branch}>
                    {branch}
                  </AutocompleteItem>
                ))}
              </Autocomplete>
            </div>
          )}

          {currentStep === 3 && (
            <div className="mb-6">
              <Table
                aria-label="Solidity files table"
                selectionMode="multiple"
                selectedKeys={new Set(selectedContracts)}
                onSelectionChange={(selection) =>
                  setSelectedContracts(Array.from(selection) as string[])
                }
              >
                <TableHeader>
                  <TableColumn>NAME</TableColumn>
                  <TableColumn>PATH</TableColumn>
                </TableHeader>
                <TableBody>
                  {solidityFiles.map((file) => (
                    <TableRow key={file.path}>
                      <TableCell>{file.name}</TableCell>
                      <TableCell>{file.path}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </div>
      </main>
    </Card>
  );
};

export default ScanStepper;
