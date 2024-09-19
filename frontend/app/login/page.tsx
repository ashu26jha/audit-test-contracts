'use client';

import { Button, Card, CardBody, Image } from '@nextui-org/react';
import { initiateGithubLogin } from '../../services/api';
import { useAuth } from '../../contexts/AuthContext';
import { useRouter } from 'next/navigation';

const LoginPage = () => {
  // If user is already logged in, redirect to dashboard
  const { user } = useAuth();
  const router = useRouter();
  if (user) {
    router.push('/dashboard');
  }
  return (
    <div className="flex items-center justify-center min-h-screen">
      <Card className="max-w-[420px] p-5">
        <CardBody className="py-10">
          <div className="flex flex-col items-center">
            <h1 className="text-2xl font-bold mb-5 text-center">AUDIT AGENT</h1>
            <Image
              src="/logo.png"
              alt="Audit Agent Logo"
              width={100}
              height={100}
              className="mb-5"
            />
            <p className="text-sm text-center mb-5">Login to Explore</p>
            <p className="text-sm text-center mb-5">
              Please continue with your GitHub account
            </p>
            <Button
              color="secondary"
              startContent={
                <Image
                  src="/github-mark.png"
                  alt="GitHub"
                  width={20}
                  height={20}
                />
              }
              onPress={initiateGithubLogin}
            >
              Continue with GitHub
            </Button>
          </div>
        </CardBody>
      </Card>
    </div>
  );
};

export default LoginPage;
