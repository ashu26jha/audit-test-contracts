'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '../../contexts/AuthContext';
import React from 'react';
import {
  Button,
  Divider,
  Card,
  CardBody,
  CardHeader,
  Chip,
} from '@nextui-org/react';
import Image from 'next/image';
import ScanStepper from '../../components/scan-stepper';
import { Hash, Calendar, AlertTriangle, FileText } from 'lucide-react';
import { getScanHistory } from '../../services/api';

interface ScanHistoryItem {
  name: string;
  logo: string;
  scan_id: string;
  status: string;
  startedAt: string;
  completedAt: string | null;
  contractFiles: string[];
  linesOfCode: {
    total_lines: number;
    code_lines: number;
    comment_lines: number;
    empty_lines: number;
  } | null;
}

const scans = [
  {
    name: 'code-alchemy',
    logo: '/path/to/code-alchemy-logo.png',
    status: 'Unpaid',
    scanId: '253152',
    scannedDate: '2 days ago',
    vulnerabilitiesFound: 23,
    contractsScanned: 3,
  },
  {
    name: 'nova-nodes',
    logo: '/path/to/nova-nodes-logo.png',
    status: 'Paid',
    scanId: '36234',
    scannedDate: '3 days ago',
    vulnerabilitiesFound: 14,
    contractsScanned: 4,
  },
  {
    name: 'secures-phere',
    logo: '/path/to/secures-phere-logo.png',
    status: 'Unpaid',
    scanId: '124511',
    scannedDate: '21 July 2024',
    vulnerabilitiesFound: 7,
    contractsScanned: 2,
  },
];

const DashboardPage = () => {
  const { user, logout, token } = useAuth();
  const router = useRouter();
  const [showStepper, setShowStepper] = useState(false);
  const [scanHistory, setScanHistory] = useState<ScanHistoryItem[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  console.log('user', user);
  console.log('showStepper', showStepper);

  useEffect(() => {
    if (!user) {
      router.push('/login');
    }
  }, [user, router]);

  if (!user) {
    return <div>Loading...</div>;
  }

  useEffect(() => {
    const fetchScanHistory = async () => {
      if (token) {
        try {
          const history = await getScanHistory(token);
          setScanHistory(history);
        } catch (error) {
          console.error('Error fetching scan history:', error);
        } finally {
          setIsLoading(false);
        }
      }
    };

    fetchScanHistory();
  }, [token]);

  const handleScanClick = (scanId: string) => {
    console.log('handleScanClick called with scanId:', scanId); // Add this line for debugging
    router.push(`/scan-results/${scanId}`);
  };

  return (
    <>
      {showStepper ? (
        <ScanStepper />
      ) : (
        <Card className="min-h-screen">
          {/* Main content */}
          <CardHeader>
            <div className="flex justify-between items-center mb-1 ml-4 mr-4 w-full">
              <h2 className="text-l font-light">Dashboard</h2>
              <Button
                color="secondary"
                className="bg-[#8B5CF6] text-white"
                onClick={() => setShowStepper(true)}
                startContent={
                  <Image
                    src="/scan-icon.svg"
                    alt="Scan"
                    width={20}
                    height={20}
                  ></Image>
                }
              >
                Scan Code
              </Button>
            </div>
          </CardHeader>
          <Divider />

          <CardBody className="overflow-y-auto">
            {scanHistory.length > 0 ? (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {scanHistory.map((scan, index) => (
                  <Card
                    key={index}
                    isPressable
                    className="bg-[#222222] cursor-pointer hover:bg-[#333333] transition-colors duration-300"
                    onClick={() => handleScanClick(scan.scan_id)}
                  >
                    <CardBody>
                      <div className="flex items-center justify-between mb-4">
                        <div className="flex items-center">
                          <div className="w-10 h-10 mr-3 bg-gray-700 rounded-full flex items-center justify-center">
                            <Image
                              src={scan.logo}
                              alt={scan.name}
                              width={24}
                              height={24}
                            />
                          </div>
                          <span className="font-semibold">{scan.name}</span>
                        </div>
                        <Chip
                          color={scan.status === 'Paid' ? 'success' : 'warning'}
                          size="sm"
                        >
                          {scan.status}
                        </Chip>
                      </div>
                      <div className="space-y-2">
                        <div className="flex items-center">
                          <Hash size={16} className="mr-2 text-gray-400" />
                          <span className="text-sm">
                            Scan ID: {scan.scan_id}
                          </span>
                        </div>
                        <div className="flex items-center">
                          <Calendar size={16} className="mr-2 text-gray-400" />
                          <span className="text-sm">
                            Scanned Date:{' '}
                            {new Date(scan.startedAt).toLocaleString()}
                          </span>
                        </div>
                        <div className="flex items-center">
                          <AlertTriangle
                            size={16}
                            className="mr-2 text-gray-400"
                          />
                          <span className="text-sm">
                            Vulnerabilities Found: {1}
                          </span>
                        </div>
                        <div className="flex items-center">
                          <FileText size={16} className="mr-2 text-gray-400" />
                          <span className="text-sm">
                            Contracts Scanned: {scan.contractFiles.length}
                          </span>
                        </div>
                      </div>
                    </CardBody>
                  </Card>
                ))}
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center h-[60vh]">
                <Image
                  src="/empty-dashboard.svg"
                  alt="No Code Scanned"
                  width={100}
                  height={100}
                />
                <h3 className="text-xl my-4">No Code Scanned</h3>
                <p className="text-gray-400 text-center">
                  You haven't scanned any code yet.
                  <br />
                  Please select a code file to scan.
                </p>
              </div>
            )}
          </CardBody>
        </Card>
      )}
    </>
  );
};

export default DashboardPage;
