"use client";

import { type FC } from "react";

import { BreadcrumbItem, Breadcrumbs } from "@nextui-org/react";
import { tv } from "tailwind-variants";

interface BreadcrumbItem {
  label: string;
  href: string;
}

interface ContainerProps {
  children: React.ReactNode;
  breadcrumbItems: BreadcrumbItem[];
  buttons?: React.ReactNode;
  disableTopPadding?: boolean;
}

const Container: FC<ContainerProps> = ({ breadcrumbItems, buttons, children, disableTopPadding }) => {
  const childContainer = tv({
    base: "pt-8 px-8 h-full overflow-y-auto",
    variants: {
      disableTopPadding: {
        true: "pt-0",
      },
    },
  });

  return (
    <section className="h-full flex flex-col">
      <div className="flex justify-between items-center p-8 border-b-2 border-b-content-1 h-[5.5rem]">
        <Breadcrumbs
          itemClasses={{
            separator: "px-2",
          }}
          separator="/"
        >
          {breadcrumbItems.map((item, index) => (
            <BreadcrumbItem key={index} href={item.href}>
              {item.label}
            </BreadcrumbItem>
          ))}
        </Breadcrumbs>
        <div>{buttons}</div>
      </div>
      <main className={childContainer({ disableTopPadding })}>{children}</main>
    </section>
  );
};

export default Container;
