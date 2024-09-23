'use client';

import React from 'react';
import { Card, CardBody, Input, Button, Avatar } from '@nextui-org/react';
import { LogOut, Github } from 'lucide-react';
import { useRouter } from 'next/navigation';

const ProfilePage: React.FC = () => {
  const router = useRouter();

  const handleLogout = () => {
    // Implement logout logic here
    console.log('Logging out...');
    // After logout, redirect to login page
    router.push('/login');
  };

  return (
    <div className="min-h-screen bg-black text-white p-8">
      <div className="flex justify-between items-center mb-8">
        <div className="text-sm text-gray-400">Dashboard / Profile</div>
        <Button variant="light" onPress={() => router.back()}>
          Go Back
        </Button>
      </div>

      <Card className="bg-[#222222] max-w-md mx-auto">
        <CardBody className="flex flex-col items-center gap-6">
          <Avatar
            src="https://i.pravatar.cc/150?u=a042581f4e29026704d"
            size="lg"
            className="w-24 h-24 text-large"
          />

          <Input
            label="Name"
            value="Quinton Pereira"
            readOnly
            className="max-w-xs"
          />

          <Input
            label="Email"
            value="quintonp23@gmail.com"
            readOnly
            className="max-w-xs"
          />

          <Input
            label="GitHub Username"
            value="@quintonp23"
            readOnly
            className="max-w-xs"
            endContent={<Github size={20} />}
          />

          <Button
            color="danger"
            variant="flat"
            onPress={handleLogout}
            startContent={<LogOut size={20} />}
            className="max-w-xs w-full"
          >
            Log Out
          </Button>
        </CardBody>
      </Card>
    </div>
  );
};

export default ProfilePage;
