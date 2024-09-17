import { useEffect } from 'react';
import { useRouter } from 'next/router';
import { useAuth } from '../../contexts/AuthContext';

const LoginSuccessPage = () => {
  const router = useRouter();
  const { setToken } = useAuth();

  useEffect(() => {
    const { token } = router.query;
    console.log('token', token);
    if (token) {
      if (typeof token === 'string') {
        setToken(token);
        router.push('/dashboard');
      } else {
        console.error('No token found in URL');
        router.push('/login');
      }
    }
  }, [router.query, router, setToken]);

  return <div>Processing login...</div>;
};

export default LoginSuccessPage;
