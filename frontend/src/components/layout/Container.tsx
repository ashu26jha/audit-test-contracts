"use client";

import { type FC } from "react";

import { BreadcrumbItem, Breadcrumbs } from "@nextui-org/react";

interface ContainerProps {
  children: React.ReactNode;
  breadcrumbItems: string[];
  buttons?: React.ReactNode;
}

const Container: FC<ContainerProps> = ({ breadcrumbItems, buttons, children }) => {
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
            <BreadcrumbItem key={index}>{item}</BreadcrumbItem>
          ))}
        </Breadcrumbs>
        <div>{buttons}</div>
      </div>
      <main className="pt-8 px-8 h-full overflow-y-auto">{children}</main>
    </section>
  );
};

export default Container;
