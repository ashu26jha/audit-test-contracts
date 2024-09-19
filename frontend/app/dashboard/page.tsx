'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '../../../frontend/contexts/AuthContext';
import { Button } from '@nextui-org/react';
import RepositorySelector from '../../../frontend/components/RepositorySelector';

const DashboardPage = () => {
  const { user, logout } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (!user) {
      router.push('/login');
    }
  }, [user, router]);

  if (!user) {
    return <div>Loading...</div>;
  }

  return (
    <div style={{ padding: '20px' }}>
      <h1>Welcome, {user.username}</h1>
      <p>Email: {user.email}</p>
      <Button
        color="danger"
        onClick={() => {
          logout();
          router.push('/login');
        }}
      >
        Logout
      </Button>
      <RepositorySelector />
    </div>
  );
};

export default DashboardPage;
