import { Button } from '@nextui-org/react';
import { initiateGithubLogin } from '../../services/api';
import { useAuth } from '../../contexts/AuthContext';
import { useRouter } from 'next/router';

const LoginPage = () => {
  // If user is already logged in, redirect to dashboard
  const { user } = useAuth();
  const router = useRouter();
  if (user) {
    router.push('/dashboard');
  }
  return (
    <div
      style={{
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        height: '100vh',
      }}
    >
      <Button color="primary" onClick={initiateGithubLogin}>
        Login with GitHub
      </Button>
    </div>
  );
};

export default LoginPage;
