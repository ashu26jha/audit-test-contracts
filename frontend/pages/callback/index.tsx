import { useEffect } from 'react';
import { useRouter } from 'next/router';
import { useAuth } from '../../contexts/AuthContext';

const CallbackPage = () => {
  const router = useRouter();
  const { setToken } = useAuth();

  useEffect(() => {
    const { token } = router.query;
    if (typeof token === 'string') {
      setToken(token);
      router.push('/dashboard');
    }
  }, [router.query, router, setToken]);

  return <div>Processing login...</div>;
};

export default CallbackPage;
