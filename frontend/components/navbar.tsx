'use client';
import {
  Navbar as NextUINavbar,
  NavbarContent,
  NavbarBrand,
} from '@nextui-org/navbar';
// import { Image } from '@nextui-org/react';
import Image from 'next/image';
import NextLink from 'next/link';
import {
  Avatar,
  Dropdown,
  DropdownTrigger,
  DropdownMenu,
  DropdownItem,
} from '@nextui-org/react';
import { useAuth } from '../contexts/AuthContext';
import { useRouter, usePathname } from 'next/navigation';
import { ChevronDownIcon } from '@heroicons/react/24/solid';
import LoginNavbar from './login-navbar';

export const Navbar = () => {
  const { user, logout } = useAuth();
  const router = useRouter();
  const pathname = usePathname();
  console.log(user);
  if (pathname === '/login') {
    return <LoginNavbar />;
  }

  const handleLogout = () => {
    logout();
    router.push('/login');
  };
  if (!user) {
    router.push('/login');
  }
  return (
    <NextUINavbar
      maxWidth="full"
      position="sticky"
      className="h-20 px-8 py-6 bg-zinc-900 shadow border-b border-zinc-800 flex flex-row"
    >
      {/* <NavbarContent className="basis-1/5 sm:basis-full" justify="start"> */}
      <NavbarBrand as="li" className="gap-3 max-w-fit">
        <NextLink className="flex justify-start items-center gap-1" href="/">
          <Image
            src="./logo.svg"
            alt="logo"
            width={120}
            height={70}
          // className="w-8 h-8"
          />
        </NextLink>
      </NavbarBrand>
      {/* </NavbarContent> */}

      <NavbarContent justify="end">
        <div className="justify-start items-center gap-1.5 flex">
          <Dropdown placement="bottom-end">
            <DropdownTrigger>
              <div className="justify-center items-center gap-2 flex cursor-pointer">
                {user && user.avatarUrl ? ( // Changed to use a single ternary operator
                  <Avatar
                    src={user.avatarUrl}
                    size="sm"
                    className="bg-zinc-700 text-zinc-300 rounded-[10px]"
                  />
                ) : <></>} <></>
                <p className="text-neutral-50 text-base leading-normal">
                  {user ? user.username : 'Guest'}
                </p>
                <ChevronDownIcon className="w-4 h-4 text-neutral-50" />
              </div>
            </DropdownTrigger>
            <DropdownMenu
              aria-label="Profile Actions"
              variant="flat"
              className="border border-gray-600 rounded-lg"
            >
              <DropdownItem
                key="profile"
                onClick={() => {
                  router.push('/profile');
                }}
              >
                Profile
              </DropdownItem>
              <DropdownItem key="support">Support Email</DropdownItem>
              <DropdownItem key="logout" color="danger" onClick={handleLogout}>
                Log out
              </DropdownItem>
            </DropdownMenu>
          </Dropdown>
        </div>
      </NavbarContent>

      {/* <NavbarContent
        className="hidden sm:flex basis-1/5 sm:basis-full"
        justify="end"
      >
        <NavbarItem className="hidden sm:flex gap-2">
          <ThemeSwitch />
        </NavbarItem>
      </NavbarContent>
      <NavbarContent
        className="hidden sm:flex basis-1/5 sm:basis-full"
        justify="end"
      >
        <Dropdown placement="bottom-end">
          <DropdownTrigger>
            <Avatar
              isBordered
              as="button"
              className="transition-transform"
              color="secondary"
              name={user ? user.username : 'Guest'}
              size="sm"
            />
          </DropdownTrigger>
          <DropdownMenu aria-label="Profile Actions" variant="flat">
            <DropdownItem
              key="profile"
              onClick={() => {
                router.push('/profile');
              }}
            >
              Profile
            </DropdownItem>
            <DropdownItem key="support">Support Email</DropdownItem>
            <DropdownItem key="logout" color="danger" onClick={handleLogout}>
              Log out
            </DropdownItem>
          </DropdownMenu>
        </Dropdown>
      </NavbarContent> */}
    </NextUINavbar>
  );
};
