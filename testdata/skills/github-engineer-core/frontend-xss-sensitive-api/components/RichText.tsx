import React from 'react';

interface Props {
  content: string;
}

export const RichText: React.FC<Props> = ({ content }) => {
  return <div dangerouslySetInnerHTML={{ __html: content }} />;
};
